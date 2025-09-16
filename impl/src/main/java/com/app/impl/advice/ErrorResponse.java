package com.app.impl.advice;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public class ErrorResponse {
    private int statusCode;
    private String message;
    private String url;
}
