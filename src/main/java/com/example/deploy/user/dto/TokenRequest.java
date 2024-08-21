package com.example.deploy.user.dto;

public record TokenRequest(
	String id,
	String email,
	String verified_email,
	String name
) {
}
