package com.ba.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/hello")
public class HelloController {
	@GetMapping
	public ResponseEntity<String> getMessage(){
		return ResponseEntity.ok("Merhaba JWT");
	}
}
