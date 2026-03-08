package com.weaponmail.config;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.cassandra.CassandraContainer;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

import java.util.List;

@TestConfiguration(proxyBeanMethods = false)
public class TestcontainersConfig {

    // Vi skapar ett nätverk så att 'kafka' hostname fungerar internt
    static Network network = Network.newNetwork();

    @SuppressWarnings("resource")
    @Bean
    public CassandraContainer scyllaDbContainer() {
        DockerImageName scyllaImage = DockerImageName.parse("scylladb/scylla:latest")
                .asCompatibleSubstituteFor("cassandra");
        
        return new CassandraContainer(scyllaImage)
                .withNetwork(network)
                .withNetworkAliases("scylladb")
                .withInitScript("schema.cql");
    }

    @SuppressWarnings("resource")
    @Bean
    public GenericContainer<?> kafkaContainer() {
        // Vi använder apache/kafka:3.9.0 precis som i din docker-compose
        return new GenericContainer<>(DockerImageName.parse("apache/kafka:3.9.0"))
                .withNetwork(network)
                .withNetworkAliases("kafka") // Detta sätter hostname till 'kafka'
                .withExposedPorts(9092)
                .withEnv("KAFKA_NODE_ID", "1")
                .withEnv("KAFKA_PROCESS_ROLES", "broker,controller")
                .withEnv("KAFKA_CONTROLLER_QUORUM_VOTERS", "1@kafka:9093")
                .withEnv("KAFKA_LISTENERS", "PLAINTEXT://kafka:29092,PLAINTEXT_HOST://kafka:9092,CONTROLLER://kafka:9093")
                // VIKTIGT: Vi annonserar localhost för testerna som körs utanför Docker
                .withEnv("KAFKA_ADVERTISED_LISTENERS", "PLAINTEXT://kafka:29092,PLAINTEXT_HOST://localhost:9092")
                .withEnv("KAFKA_CONTROLLER_LISTENER_NAMES", "CONTROLLER")
                .withEnv("KAFKA_LISTENER_SECURITY_PROTOCOL_MAP", "PLAINTEXT:PLAINTEXT,PLAINTEXT_HOST:PLAINTEXT,CONTROLLER:PLAINTEXT")
                .withEnv("KAFKA_INTER_BROKER_LISTENER_NAME", "PLAINTEXT")
                .withEnv("CLUSTER_ID", "MkU3OEVBNTcwNTJENDM2Qk")
                .withEnv("KAFKA_AUTO_CREATE_TOPICS_ENABLE", "true")
                .waitingFor(Wait.forLogMessage(".*Transitioning from RECOVERY to RUNNING.*", 1));
    }

    @DynamicPropertySource
    static void overrideProps(DynamicPropertyRegistry registry, 
                             GenericContainer<?> kafka, 
                             CassandraContainer scylla) {
        
        // Här mappar vi testernas anslutning till den dynamiska porten på localhost
        registry.add("spring.kafka.bootstrap-servers", 
            () -> "localhost:" + kafka.getMappedPort(9092));
        
        registry.add("spring.cassandra.contact-points", () -> 
            scylla.getHost() + ":" + scylla.getMappedPort(9042));
        registry.add("spring.cassandra.local-datacenter", () -> "datacenter1");
        registry.add("spring.cassandra.keyspace-name", () -> "weaponmail");
        registry.add("weaponmail.kafka.topics.inbox-events", () -> "inbox.events");
    }
}