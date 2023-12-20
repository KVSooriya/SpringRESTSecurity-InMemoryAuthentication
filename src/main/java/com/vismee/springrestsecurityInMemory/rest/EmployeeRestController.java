package com.vismee.springrestsecurityInMemory.rest;

import com.vismee.springrestsecurityInMemory.customException.EmployeeNotFoundException;
import com.vismee.springrestsecurityInMemory.entity.Employee;
import com.vismee.springrestsecurityInMemory.service.EmployeeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api")
public class EmployeeRestController
{
    private EmployeeService employeeService;

    @Autowired
    public EmployeeRestController(EmployeeService employeeService) {
        this.employeeService = employeeService;
    }

    @GetMapping("/employees")
    public List<Employee> getEmployees()
    {
        return employeeService.findAll();
    }

    @GetMapping("/employees/{employeeId}")
    public Employee getEmployeeById(@PathVariable int employeeId)
    {
        Employee employee = employeeService.findById(employeeId);

        if(employee == null)
            throw new EmployeeNotFoundException("Employee not found for the id " +employeeId);

        return employee;
    }

    // Any JSON data posted will come as RequestBody and @RequestBody helps to bind JSON to POJO
    @PostMapping("/employees")
    public Employee addEmployee(@RequestBody Employee employee)
    {
        /* if they provide id in RequestBody, update the id to 0 in order to add the data
         else the data gets updated for the provided id based on merge method we written on dao code */
         employee.setId(0);
         Employee dbEmployee = employeeService.save(employee);
         return dbEmployee;
    }

    @PutMapping("/employees")
    public Employee updateEmployee(@RequestBody Employee employee)
    {
        Employee emp = employeeService.findById(employee.getId());

        /* If employee is not found for the id , throw exception. Else it will perform insert on db table
           due to merge in dao since merge performs insert/save or update based on id value.
           If id is found, it will perform update else insert into db table. So to avoid this throw
           exception if the id is not found.
        */
        if(emp == null)
            throw new EmployeeNotFoundException("Employee id not found for the update");

        Employee dbEmployee = employeeService.save(employee);
        return dbEmployee;
    }

    @DeleteMapping("/employees/{employeeId}")
    public String deleteEmployee(@PathVariable int employeeId)
    {
        Employee employee = employeeService.findById(employeeId);

        if(employee == null)
            throw new EmployeeNotFoundException("Employee not found for the id " +employeeId);

        employeeService.deleteById(employeeId);
        return "Employee deleted for the id " +employeeId;
    }
}
