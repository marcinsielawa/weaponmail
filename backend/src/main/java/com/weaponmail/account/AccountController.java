package com.weaponmail.account;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api/account")
public class AccountController {

    private final AccountService accountService;

    public AccountController(AccountService accountService) {
        this.accountService = accountService;
    }

    @PostMapping("/signup")
    public Mono<Void> signUp(@RequestBody UserAccount account) {
        return accountService.signUp(account);
    }

    @PostMapping("/login")
    public Mono<AuthResponse> login(@RequestBody LoginRequest login) {
        return accountService.login(login.username, login.loginHash);
    }

    @PostMapping("/logout")
    public Mono<Void> logout(@RequestHeader("Authorization") String token) {
        return accountService.logout(token.replace("Bearer ", ""));
    }
}
