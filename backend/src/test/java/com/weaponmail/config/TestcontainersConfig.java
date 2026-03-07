package com.weaponmail.config;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
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
    @ServiceConnection
    CassandraContainer scyllaDbContainer() {
        // Vi använder ScyllaDB-image men med Cassandras test-adapter
        return new CassandraContainer(DockerImageName.parse("scylladb/scylla:latest"))
                .withInitScript("scylla.cql"); // Skapa keyspace/tabeller vid start
    }

    @Bean
    @ServiceConnection
    KafkaContainer kafkaContainer() {
        // Kör Kafka i KRaft-läge (ingen Zookeeper behövs!)
        return new KafkaContainer(DockerImageName.parse("confluentinc/cp-kafka:latest"));
    }
    
    // Detta mappar om värdena i din application.yml till containrarnas dynamiska portar
    @DynamicPropertySource
    static void overrideProps(DynamicPropertyRegistry registry, 
                             KafkaContainer kafka, 
                             CassandraContainer scylla) {
        
        // Mappa Kafka
        registry.add("spring.kafka.bootstrap-servers", kafka::getBootstrapServers);
        
        // Mappa ScyllaDB (Cassandra)
        registry.add("spring.cassandra.contact-points", () -> 
            scylla.getHost() + ":" + scylla.getMappedPort(9042));
        registry.add("spring.cassandra.local-datacenter", () -> "datacenter1");
        registry.add("spring.cassandra.keyspace-name", () -> "weaponmail");
    }
}