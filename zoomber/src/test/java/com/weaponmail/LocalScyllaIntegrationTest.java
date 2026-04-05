package com.weaponmail;

import com.weaponmail.account.AccountRepository;
import com.weaponmail.account.UserAccount;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import reactor.test.StepVerifier;

import java.util.UUID;

/**
 * Tests against a manually started Docker ScyllaDB on localhost:9042.
 * Ensure you run: docker run --name scylla-local -p 9042:9042 -d scylladb/scylla
 */
@SpringBootTest
class LocalScyllaIntegrationTest {

    @Autowired
    private AccountRepository accountRepository;

    @DynamicPropertySource
    static void localScyllaProperties(DynamicPropertyRegistry registry) {
        // Pointing to your Docker Desktop mapping
        registry.add("spring.cassandra.contact-points", () -> "127.0.0.1:9042");
        registry.add("spring.cassandra.local-datacenter", () -> "datacenter1");
        registry.add("spring.cassandra.keyspace-name", () -> "weaponmail");
        registry.add("spring.cassandra.schema-action", () -> "create_if_not_exists");
    }

    //@Test
    void verifyLocalScyllaIsAlive() {
        String testUser = "local-test-" + UUID.randomUUID().toString().substring(0, 8) + "@weaponmail.io";
        
        UserAccount account = new UserAccount();
        account.username = testUser;
        account.loginHash = "local-secret-hash";
        account.createdAt = System.currentTimeMillis();

        // 1. Save to your local Docker Scylla
        var saveAction = accountRepository.save(account);

        StepVerifier.create(saveAction)
            .expectNextMatches(saved -> saved.username.equals(testUser))
            .verifyComplete();

        // 2. Read back from your local Docker Scylla
        var findAction = accountRepository.findById(testUser);

        StepVerifier.create(findAction)
            .expectNextMatches(found -> found.loginHash.equals("local-secret-hash"))
            .verifyComplete();

        System.out.println("✅ Successfully talked to Local Docker ScyllaDB at 127.0.0.1:9042");
    }

    @Test
    void listAllLocalAccounts() {
        System.out.println("--- Current Accounts in Local Scylla ---");
        accountRepository.findAll()
            .doOnNext(acc -> System.out.println("👤 " + acc.username))
            .as(StepVerifier::create)
            .thenConsumeWhile(x -> true)
            .verifyComplete();
    }
}