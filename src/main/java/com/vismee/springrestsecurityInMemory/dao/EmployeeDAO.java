package com.vismee.springrestsecurityInMemory.dao;

import com.vismee.springrestsecurityInMemory.entity.Employee;

import java.util.List;

public interface EmployeeDAO
{
    List<Employee> findAll();
    Employee findById(int id);
    Employee save(Employee employee);
    void deleteById(int id);
}
