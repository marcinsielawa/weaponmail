package com.weaponmail;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;

@SpringBootTest
@ActiveProfiles("test")
@ContextConfiguration(initializers = CassandraContainerInitializer.class)
class MessageBackendApplicationTests {

	@Test
	void contextLoads() {
	}

}
