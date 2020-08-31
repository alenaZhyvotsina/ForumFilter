package telran.ashkelon2020.accounting.service.filters;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Service;

import telran.ashkelon2020.accounting.service.security.AccountingSecurity;

@Service
@Order(50)
public class ValidateUserFilter implements Filter{

	@Autowired
	AccountingSecurity securityService;
	
	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		
		String path = request.getServletPath();
		
		if(checkPathOnValidateUser(path)) {			
			String loginPath = path.substring(path.lastIndexOf("/") + 1); //path.split("/")[2];
			if(!request.getUserPrincipal().getName().equalsIgnoreCase(loginPath)) {
				response.sendError(403);
				return;
			}			
		}
		chain.doFilter(request, response);
		
	}

	private boolean checkPathOnValidateUser(String path) {
		return !path.equalsIgnoreCase("/account/user/password") && path.matches("/account/user/\\w*");
	}

}
