package com.authorizatiion.demo;
 
 
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
 
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
 
import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;
 
@Entity
@Table(name = "employee_master")
public class EmployeeMaster implements UserDetails {
 
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "staff_id")
    private Long id;
    
    @Column(name = "user_id")
    private String userId;
    @Column(name = "password")
    private String password;
    @Column(name = "role")
    private String role;
    
    @Column(name = "f_name")
    private String fName;
    
    @Column(name = "l_name")
    private String lName;
    
    @Column(name = "m_name")
    private String mName;
    
    @Column(name = "email_id")
    private String emailId;
    
    
 
 
    // Getters and setters
 
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Set.of(role).stream()
            .map(SimpleGrantedAuthority::new)
            .collect(Collectors.toSet());
    }
 
    @Override
    public String getPassword() {
        return password;
    }
 
    @Override
    public String getUsername() {
        return userId;
    }
 
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }
 
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }
 
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }
 
    @Override
    public boolean isEnabled() {
        return true;
    }

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getUserId() {
		return userId;
	}

	public void setUserId(String userId) {
		this.userId = userId;
	}

	public String getRole() {
		return role;
	}

	public void setRole(String role) {
		this.role = role;
	}

	public String getfName() {
		return fName;
	}

	public void setfName(String fName) {
		this.fName = fName;
	}

	public String getlName() {
		return lName;
	}

	public void setlName(String lName) {
		this.lName = lName;
	}

	public String getmName() {
		return mName;
	}

	public void setmName(String mName) {
		this.mName = mName;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getEmailId() {
		return emailId;
	}

	public void setEmailId(String emailId) {
		this.emailId = emailId;
	}
    
    
    
}
 
 