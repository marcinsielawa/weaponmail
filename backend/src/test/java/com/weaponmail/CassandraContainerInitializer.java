package com.weaponmail;

import com.datastax.oss.driver.api.core.CqlSession;
import org.springframework.boot.test.util.TestPropertyValues;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.testcontainers.containers.CassandraContainer;
import org.testcontainers.utility.DockerImageName;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

public class CassandraContainerInitializer
        implements ApplicationContextInitializer<ConfigurableApplicationContext> {

    static final CassandraContainer<?> CASSANDRA =
            new CassandraContainer<>(DockerImageName.parse("cassandra:4.1"))
                    .withStartupTimeout(java.time.Duration.ofMinutes(3));

    static {
        CASSANDRA.start();
        applySchema();
    }

    private static void applySchema() {
        try {
            var schemaStream = CassandraContainerInitializer.class.getResourceAsStream("/schema.cql");
            if (schemaStream == null) {
                throw new RuntimeException("schema.cql not found on classpath");
            }
            String schema;
            try (schemaStream) {
                schema = new String(schemaStream.readAllBytes(), StandardCharsets.UTF_8);
            }
            try (CqlSession session = CqlSession.builder()
                    .addContactPoint(new InetSocketAddress(
                            CASSANDRA.getHost(), CASSANDRA.getMappedPort(9042)))
                    .withLocalDatacenter(CASSANDRA.getLocalDatacenter())
                    .build()) {
                for (String statement : schema.split(";")) {
                    String trimmed = statement.trim();
                    if (!trimmed.isEmpty()) {
                        session.execute(trimmed);
                    }
                }
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to apply schema.cql", e);
        }
    }

    @Override
    public void initialize(ConfigurableApplicationContext ctx) {
        TestPropertyValues.of(
                "spring.cassandra.contact-points=" + CASSANDRA.getHost() + ":" + CASSANDRA.getMappedPort(9042),
                "spring.cassandra.local-datacenter=" + CASSANDRA.getLocalDatacenter(),
                "spring.cassandra.port=" + CASSANDRA.getMappedPort(9042)
        ).applyTo(ctx.getEnvironment());
    }
}
