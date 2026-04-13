package com.weaponmail;

import java.time.Duration;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.cassandra.CassandraContainer;
import org.testcontainers.kafka.KafkaContainer;
import org.testcontainers.utility.DockerImageName;

@TestConfiguration(proxyBeanMethods = false)
public class TestWeaponMailApplication {

   
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

    

    public static void main(String[] args) {
        SpringApplication.from(MessageBackendApplication::main)
            .with(TestWeaponMailApplication.class)
            .run(args);
    }
}