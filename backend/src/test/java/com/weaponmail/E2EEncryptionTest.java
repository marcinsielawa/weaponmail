package com.weaponmail;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.cassandra.CassandraContainer;
import org.testcontainers.kafka.KafkaContainer;
import org.testcontainers.utility.DockerImageName;

import com.datastax.oss.driver.api.core.uuid.Uuids;
import com.weaponmail.account.AccountRepository;
import com.weaponmail.crypto.CryptoTestUtils;
import com.weaponmail.message.MessageEntity;
import com.weaponmail.message.MessageKey;
import com.weaponmail.message.MessageRequest;
import com.weaponmail.message.MessageService;
import com.weaponmail.message.event.InboxEvent;
import com.weaponmail.stream.InboxStreamService;

import jakarta.annotation.Resource;
import reactor.core.publisher.Flux;
import reactor.test.StepVerifier;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.Set;
import java.util.UUID;

@SpringBootTest
class E2EEncryptionTest {
    
    // 1. Static Containers
    static final KafkaContainer kafka = new KafkaContainer(
        DockerImageName.parse("apache/kafka:latest")
    )
            
            .withStartupTimeout(Duration.ofSeconds(90))
            
            ;
    
            

    static final CassandraContainer scylla = new CassandraContainer(
        DockerImageName.parse("scylladb/scylla:6.0.1")
            .asCompatibleSubstituteFor("cassandra")
    )
    .withInitScript("schema.cql")
    .withStartupTimeout(Duration.ofMinutes(2));

    static {
        kafka.start();
        scylla.start();
    }
    
    // 2. Override properties directly in the test class
    @DynamicPropertySource
    static void overrideProperties(DynamicPropertyRegistry registry) {
        String bootstrapServers = kafka.getBootstrapServers();
        System.out.println("🚀 Testcontainers Kafka is running at: " + bootstrapServers);
        
        registry.add("spring.kafka.bootstrap-servers", kafka::getBootstrapServers);
        registry.add("weaponmail.kafka.topics.inbox-events", () -> "inbox.events");
        
        // 🔥 CRITICAL: Prevent Kafka consumers from starting automatically and looping on 9092
        registry.add("spring.kafka.listener.auto-startup", () -> "false");

        // Scylla properties...
        registry.add("spring.cassandra.contact-points", 
            () -> scylla.getContactPoint().getHostString() + ":" + scylla.getContactPoint().getPort());
        registry.add("spring.cassandra.local-datacenter", scylla::getLocalDatacenter);
        registry.add("spring.cassandra.keyspace-name", () -> "weaponmail");
        registry.add("spring.cassandra.schema-action", () -> "create_if_not_exists");
    }
    
    @Resource
    AccountRepository accountRepository;
    
    @Autowired
    private MessageService service;
    
    @Autowired
    private InboxStreamService streamService; // The SSE bridge
    
    @Autowired
    BeanFactory context;
    
    @Autowired
    private org.springframework.kafka.config.KafkaListenerEndpointRegistry kafkaRegistry;

    @Autowired
    private org.springframework.kafka.config.KafkaListenerEndpointRegistry registry;
    
    @Autowired
    private org.springframework.messaging.handler.annotation.support.MessageHandlerMethodFactory messageHandlerMethodFactory;
    
    @TestConfiguration
    static class ManualKafkaConfig {
        @Bean
        public org.springframework.messaging.handler.annotation.support.DefaultMessageHandlerMethodFactory messageHandlerMethodFactory() {
            var factory = new org.springframework.messaging.handler.annotation.support.DefaultMessageHandlerMethodFactory();
            // This will allow Spring to map the JSON payload to the InboxEvent method argument
            return factory;
        }
    }
    
    @Autowired
    private org.springframework.kafka.config.ConcurrentKafkaListenerContainerFactory<String, InboxEvent> containerFactory;
    
    @Test
    void shouldPerformFullE2EEFlow() throws Exception {
        
        String bootstrapServers = kafka.getBootstrapServers();
        System.out.println("🚀 Testcontainers Kafka is running at: " + bootstrapServers);
        
        //streamService = context.getBean(InboxStreamService.class);
        
        containerFactory.getConsumerFactory().updateConfigs(
                java.util.Map.of(org.apache.kafka.clients.consumer.ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers)
            );
        
        var endpoint = new org.springframework.kafka.config.MethodKafkaListenerEndpoint<String, InboxEvent>();
        endpoint.setId("manual-inbox-listener");
        endpoint.setGroupId("test-group-" + java.util.UUID.randomUUID());
        endpoint.setTopics("inbox.events");
        endpoint.setBean(streamService);
        endpoint.setMethod(streamService.getClass().getMethod("onInboxEvent", InboxEvent.class));

        endpoint.setBeanFactory(context);
        endpoint.setMessageHandlerMethodFactory(messageHandlerMethodFactory);
        
        // 2. Register and START the container only now
        registry.registerListenerContainer(endpoint, 
            context.getBean(org.springframework.kafka.config.KafkaListenerContainerFactory.class), true);

        kafkaRegistry.getListenerContainers().forEach(container -> container.start());
        verifyAccountRepositoryWorks2();
        
        final String originalMessage = "The eagle has landed in Stockholm";
        final String targetEmail     = "zolem@weaponmail.io";
        final UUID   threadId        = UUID.randomUUID();
        
        // ── 1. RECIPIENT SETUP ─────────────────────────────────────────────────
        AsymmetricCipherKeyPair    recipientKeys = CryptoTestUtils.generateX25519KeyPair();
        X25519PublicKeyParameters  recipientPub  = (X25519PublicKeyParameters)  recipientKeys.getPublic();
        X25519PrivateKeyParameters recipientPriv = (X25519PrivateKeyParameters) recipientKeys.getPrivate();
        
        Thread.sleep(2000); 
        
        // ── 2. Open stream        
        Flux<InboxEvent> eventStream = streamService.streamFor(targetEmail)
                .doOnSubscribe(s -> System.out.println("📡 Test subscribed to SSE stream for " + targetEmail))
                .doOnNext(e -> System.out.println("📥 Test received event from stream: " + e.messageId()));


        // ── 3. SENDER: Encrypt ─────────────────────────────────────────────────
        // Generate a random 32-byte AES body key
        byte[] messageKey = new byte[32];
        new SecureRandom().nextBytes(messageKey);

        // Encrypt the body with the AES key
        String encryptedBody = CryptoTestUtils.encrypt(originalMessage, messageKey);

        // Generate an ephemeral X25519 keypair (perfect forward secrecy)
        AsymmetricCipherKeyPair ephemeral    = CryptoTestUtils.generateX25519KeyPair();
        X25519PublicKeyParameters  ephPub    = (X25519PublicKeyParameters)  ephemeral.getPublic();
        X25519PrivateKeyParameters ephPriv   = (X25519PrivateKeyParameters) ephemeral.getPrivate();

        // ECDH: derive shared secret using ephemeral private + recipient public
        byte[] sharedSecret = CryptoTestUtils.calculateSharedSecret(ephPriv, recipientPub);

        // Wrap (encrypt) the AES message key with the shared secret
        // We Base64-encode the raw key bytes before encrypting so decrypt → Base64.decode works.
        String wrappedKey = CryptoTestUtils.encrypt(
                Base64.getEncoder().encodeToString(messageKey), sharedSecret);

        String ephemeralPublicKeyBase64 = CryptoTestUtils.encodePublicKey(ephPub);

        // ── 3. SERVER: Build and "store" the message ───────────────────────────
        // Construct MessageRequest with the FULL updated signature (10 fields).
        MessageRequest request = new MessageRequest(
                targetEmail,
                null,                           // threadId — null for new thread
                "Secret Operation",             // subject (cleartext metadata)
                encryptedBody,
                wrappedKey,
                ephemeralPublicKeyBase64,
                "BLIND-HASH-TOKEN-XYZ",         // senderBlindToken
                "ENCRYPTED-SENDER-PLACEHOLDER", // encryptedSender (not exercised here)
                Set.of(),                       // searchTokens (empty for this test)
                false                           // sealed
        );

        // Build the entity that the mock repository will return on read-back.
        // This simulates a Cassandra round-trip without touching a real DB.
        MessageKey key = new MessageKey(targetEmail, threadId, Uuids.timeBased());
        MessageEntity storedEntity = new MessageEntity();
        storedEntity.setKey(key);
        storedEntity.setSubject(request.subject());
        storedEntity.setEncryptedBody(request.encryptedBody());
        storedEntity.setMessageKey(request.messageKey());
        storedEntity.setSenderPublicKey(request.senderPublicKey());
        storedEntity.setSenderBlindToken(request.senderBlindToken());
        storedEntity.setEncryptedSender(request.encryptedSender());
        storedEntity.setSearchTokens(request.searchTokens());
        storedEntity.setSealed(request.sealed());

        // Wire mock: save returns the entity, findAll returns it, findById returns it.
        //when(messageRepository.save(any(MessageEntity.class))).thenReturn(Mono.just(storedEntity));
        //when(messageRepository.findAllByKeyRecipient(targetEmail)).thenReturn(Flux.just(storedEntity));
        //when(messageRepository.findById(any(MessageKey.class))).thenReturn(Mono.just(storedEntity));
        
        // ── 4. EXECUTE & VERIFY BACKBONE (Kafka -> SSE) ──────────────────────
        // We use StepVerifier to wait for the event to propagate through Kafka -> @KafkaListener -> Sink
        
        StepVerifier.create(service.sendMessage(request))
        .expectComplete()
        .verify(Duration.ofSeconds(10));
        
    System.out.println("✅ 1. Message sent and persisted to Scylla.");
        
        
    StepVerifier.create(streamService.streamFor(targetEmail).take(1))
    .assertNext(event -> {
        assertEquals(targetEmail, event.recipient());
        assertEquals(request.subject(), event.subject());
        System.out.println("🚀 2. Backbone Verified! Event received: " + event.messageId());
    })
    .expectComplete()
    .verify(Duration.ofSeconds(10));
    
    
    

        // ── 4. RECIPIENT: Fetch → Decrypt ──────────────────────────────────────
        StepVerifier.create(
            service.getMessages(targetEmail)
                   .flatMap(summary -> service.getMessageById(
                           targetEmail,
                           summary.threadId(),
                           summary.id()))
        ).assertNext(detail -> {
            try {
                // Re-derive the shared secret from the recipient's side:
                //   ECDH(recipient.priv, ephemeral.pub) == ECDH(ephemeral.priv, recipient.pub) ✓
                X25519PublicKeyParameters senderEphemeralPub =
                        CryptoTestUtils.decodePublicKey(detail.senderPublicKey());
                byte[] readerSecret =
                        CryptoTestUtils.calculateSharedSecret(recipientPriv, senderEphemeralPub);

                // Unwrap the AES message key
                String decryptedKmBase64 = CryptoTestUtils.decrypt(detail.messageKey(), readerSecret);
                byte[] actualMessageKey  = Base64.getDecoder().decode(decryptedKmBase64);

                // Decrypt the body
                String decryptedMessage = CryptoTestUtils.decrypt(detail.encryptedBody(), actualMessageKey);

                assertEquals(originalMessage, decryptedMessage,
                        "Decrypted message must exactly match the original plaintext");

                System.out.println("✅ E2EE Spring Verified. Decrypted: " + decryptedMessage);

            } catch (Exception e) {
                throw new RuntimeException("Decryption pipeline failed", e);
            }
        })
        .expectComplete()
        .verify(Duration.ofSeconds(10)); // 🔥 TIMEOUT: Don't wait forever. Fail after 10s.
    }    
    
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
    
    void listAllLocalAccounts() {
        System.out.println("--- Current Accounts in Local Scylla ---");
        accountRepository.findAll()
            .doOnNext(acc -> System.out.println("👤 " + acc.username))
            .as(StepVerifier::create)
            .thenConsumeWhile(x -> true)
            .expectComplete()
            .verify(Duration.ofSeconds(5));
    }
}