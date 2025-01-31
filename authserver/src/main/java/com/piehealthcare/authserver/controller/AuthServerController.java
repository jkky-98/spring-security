package com.piehealthcare.authserver.controller;

import com.piehealthcare.authserver.dto.JwtResponseDto;
import com.piehealthcare.authserver.dto.ResponseDto;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@Slf4j
public class AuthServerController {

    @PostMapping("")
    public ResponseEntity<?> authenticate(@RequestHeader("Authorization") String authorizationHeader) {
        log.info("Authenticating with Authorization Header : {}", authorizationHeader);
        JwtResponseDto jwtResponseDto = new JwtResponseDto();
        jwtResponseDto.setAccessToken(authorizationHeader);

        ResponseDto<JwtResponseDto> responseDto = new ResponseDto<>(
                HttpStatus.OK.value(),
                "Successfully authenticated",
                null
        );
        return ResponseEntity.ok(responseDto);
    }
}
