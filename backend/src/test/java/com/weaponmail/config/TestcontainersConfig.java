package com.weaponmail.config;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.cassandra.CassandraContainer;
import org.testcontainers.kafka.KafkaContainer;
import org.testcontainers.utility.DockerImageName;

@TestConfiguration(proxyBeanMethods = false)
public class TestcontainersConfig {

    @SuppressWarnings("resource")
    @Bean
    public CassandraContainer scyllaDbContainer() {
        return new CassandraContainer(DockerImageName.parse("scylladb/scylla:latest"))
                .withInitScript("schema.cql"); // Ändrat till schema.cql som finns i resources
    }

    @Bean
    public KafkaContainer kafkaContainer() {
        return new KafkaContainer(DockerImageName.parse("confluentinc/cp-kafka:latest"));
    }

    // Vi mappar properties manuellt för att undvika @ServiceConnection-felet
    @DynamicPropertySource
    static void overrideProps(DynamicPropertyRegistry registry, 
                             KafkaContainer kafka, 
                             CassandraContainer scylla) {
        
        // Kafka
        registry.add("spring.kafka.bootstrap-servers", kafka::getBootstrapServers);
        
        // ScyllaDB / Cassandra
        registry.add("spring.cassandra.contact-points", () -> 
            scylla.getHost() + ":" + scylla.getMappedPort(9042));
        registry.add("spring.cassandra.local-datacenter", () -> "datacenter1");
        registry.add("spring.cassandra.keyspace-name", () -> "weaponmail");
    }
}