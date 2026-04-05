package com.weaponmail;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.cassandra.CassandraContainer;
import org.testcontainers.utility.DockerImageName;

import com.weaponmail.account.AccountRepository;

import reactor.test.StepVerifier;

import java.time.Duration;
import java.util.UUID;

@SpringBootTest
class WeaponMailApplicationTests {

    @Autowired
    private AccountRepository accountRepository;

    // 1. Define Static Container
    static final CassandraContainer scylla = new CassandraContainer(
        DockerImageName.parse("scylladb/scylla:6.0.1")
            .asCompatibleSubstituteFor("cassandra")
    )
    .withInitScript("schema.cql")
    .withStartupTimeout(Duration.ofMinutes(2));

    static {
        scylla.start();
    }

    // 2. Register properties
    @DynamicPropertySource
    static void overrideProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.cassandra.contact-points", 
            () -> scylla.getContactPoint().getHostString() + ":" + scylla.getContactPoint().getPort());
        registry.add("spring.cassandra.local-datacenter", scylla::getLocalDatacenter);
        registry.add("spring.cassandra.keyspace-name", () -> "weaponmail");
        registry.add("spring.cassandra.schema-action", () -> "create_if_not_exists");
    }

    @Test
    void verifyAccountRepositoryWorks() {
        com.weaponmail.account.UserAccount account = new com.weaponmail.account.UserAccount();
        account.username  = "marcin" + UUID.randomUUID().toString() + "@weaponmail.io";
        account.loginHash = "secure-hash3";
        
        StepVerifier.create(accountRepository.save(account))
            .expectNextCount(1)
            .verifyComplete();

        StepVerifier.create(accountRepository.findById(account.username))
            .expectNextMatches(found -> found.loginHash.equals("secure-hash3"))
            .verifyComplete();
        
        listAllLocalAccounts();
    }
    
    @Test
    void verifyAccountRepositoryWorks2() {
        com.weaponmail.account.UserAccount account = new com.weaponmail.account.UserAccount();
        account.username  = "marcin" + UUID.randomUUID().toString() + "@weaponmail.io";
        account.loginHash = "secure-hash3";
        
        StepVerifier.create(accountRepository.save(account))
            .expectNextCount(1)
            .verifyComplete();

        StepVerifier.create(accountRepository.findById(account.username))
            .expectNextMatches(found -> found.loginHash.equals("secure-hash3"))
            .verifyComplete();
        
        listAllLocalAccounts();
    }
    
    //@Test
    void listAllLocalAccounts() {
        System.out.println("--- Current Accounts in Local Scylla ---");
        accountRepository.findAll()
            .doOnNext(acc -> System.out.println("👤 " + acc.username))
            .as(StepVerifier::create)
            .thenConsumeWhile(x -> true)
            .verifyComplete();
    }
}