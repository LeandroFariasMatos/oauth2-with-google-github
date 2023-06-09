package com.projeto.oauth2withgooglegithub;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@Controller
public class HomeController {

    @GetMapping
    public String home(@RequestParam(name = "logout",required = false,defaultValue = "true") boolean logout) {
        return "index";
    }

    @GetMapping("/login")
    String login(){
        return "app-user/login";
    }

}
