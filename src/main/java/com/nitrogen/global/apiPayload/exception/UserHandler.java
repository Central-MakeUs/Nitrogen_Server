package com.nitrogen.global.apiPayload.exception;

import com.nitrogen.global.apiPayload.code.status.ErrorStatus;

public class UserHandler extends GeneralException{
    public UserHandler(ErrorStatus errorStatus) {
        super(errorStatus);
    }
}
