package com.weaponmail;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import com.weaponmail.message.MessageService;

@SpringBootTest
public class ContextTest {

    @Autowired
    private MessageService service;

    @Test
    void foobar() {
       
    }
}