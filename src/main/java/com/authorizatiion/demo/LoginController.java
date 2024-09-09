package com.authorizatiion.demo;

 
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.ModelAndView;

@Controller
public class LoginController {

	@GetMapping("/login")
    public ModelAndView loginPage() {
        return new ModelAndView("login");
    }

	  @GetMapping("/register")
	    public String showRegistrationForm(Model model) {
	        model.addAttribute("clientForm", new ClientForm());
	        return "register"; 
	    }

	    @PostMapping("/clients/add")
	    public String addClient(@ModelAttribute("clientForm") ClientForm clientForm) {
 	        System.out.println("Client Name: " + clientForm.getClientName());
	        System.out.println("Client Secret: " + clientForm.getClientSecret());
	        System.out.println("Redirect URI: " + clientForm.getRedirectUri());
	        
 	        return "redirect:/register";
	    }
   
}	
