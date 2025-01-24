package com.piehealthcare.authserver.dto;

import lombok.Data;

@Data
public class ResponseDto<T> {
    private Integer status;
    private String message;
    private T data;
}
