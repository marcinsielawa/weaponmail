package com.weaponmail.config;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.cassandra.CassandraContainer;
import org.testcontainers.kafka.KafkaContainer;
import org.testcontainers.utility.DockerImageName;
import java.time.Duration;

@TestConfiguration(proxyBeanMethods = false)
public class TestcontainersConfig {

    // 1. Define Static Containers (Singleton Pattern)
    static final KafkaContainer kafka = new KafkaContainer(
        DockerImageName.parse("apache/kafka:latest")
    ).withStartupTimeout(Duration.ofSeconds(90));

    static final CassandraContainer scylla = new CassandraContainer(
        DockerImageName.parse("scylladb/scylla:6.0.1") // Specify version for stability
        .asCompatibleSubstituteFor("cassandra")
    )
    .withInitScript("schema.cql")
    .withStartupTimeout(Duration.ofMinutes(2));

    // 2. Start them eagerly in a static block
    static {
        kafka.start();
        scylla.start();
    }

    // 3. Override properties for BOTH before Context starts
    @DynamicPropertySource
    static void overrideProperties(DynamicPropertyRegistry registry) {
        // Kafka
        registry.add("spring.kafka.bootstrap-servers", kafka::getBootstrapServers);
        
        // Scylla / Cassandra
        registry.add("spring.cassandra.contact-points", 
            () -> scylla.getContactPoint().getHostString() + ":" + scylla.getContactPoint().getPort());
        registry.add("spring.cassandra.local-datacenter", scylla::getLocalDatacenter);
        registry.add("spring.cassandra.keyspace-name", () -> "weaponmail");
        
        // Ensure schema action matches test needs
        registry.add("spring.cassandra.schema-action", () -> "create_if_not_exists");
        
        System.out.println("Kutas * * * ** * ");
        
        System.out.println(scylla.getContactPoint().getHostString());
        System.out.println(scylla.getContactPoint().getPort());
        
        System.out.println("Kutas * * * ** * ");
        
    }
}