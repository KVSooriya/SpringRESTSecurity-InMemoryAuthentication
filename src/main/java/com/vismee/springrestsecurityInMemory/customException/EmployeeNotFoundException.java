package com.vismee.springrestsecurityInMemory.customException;

public class EmployeeNotFoundException extends RuntimeException
{
    public EmployeeNotFoundException(String message) {
        super(message);
    }
}
