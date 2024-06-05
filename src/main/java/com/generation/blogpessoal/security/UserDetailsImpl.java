package com.generation.blogpessoal.security;

import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.generation.blogpessoal.model.Usuario;

public class UserDetailsImpl implements UserDetails {

	private static final long serialVersionUID = 1L;

	private String userName;
	private String password;
	
	//classe de segurança que tras autorização de acesso que o usuario tem
	private List<GrantedAuthority> authorities;

	public UserDetailsImpl(Usuario user) {
		this.userName = user.getUsuario();
		this.password = user.getSenha();
	}

	public UserDetailsImpl() {	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		// autorizações de acesso do usuario
		return authorities;
	}

	@Override
	public String getPassword() {
		//retorna a senha do usuario
		return password;
	}

	@Override
	public String getUsername() {

		return userName;
	}

	@Override
	public boolean isAccountNonExpired(){
		//
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		//se a conta do usuario não está bloqueada = true
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		//se a credencial não estiver expirada = true
		return true;
	}

	@Override
	public boolean isEnabled() {
		//se o usuario está habilitado = true
		return true;
	}
}
