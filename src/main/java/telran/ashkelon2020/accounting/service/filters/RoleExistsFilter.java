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
@Order(30)
public class RoleExistsFilter implements Filter{

	@Autowired
	AccountingSecurity securityService;
	
	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		
		String path = request.getServletPath();
		String method = request.getMethod();
		
		if(checkPathAndMethodOnRoles(path, method)) {			
			if(securityService.isBanned(request.getUserPrincipal().getName())) {
				response.sendError(403, "User is banned");
				return;
			} 
		}
		chain.doFilter(request, response);
		
	}

	private boolean checkPathAndMethodOnRoles(String path, String method) {
		boolean res = "/account/login".equalsIgnoreCase(path) ||
					  (path.matches("/account/user/\\w*") && "Put".equalsIgnoreCase(method));
		
		res = res || (path.matches("/forum/post/\\w*") && "POST".equalsIgnoreCase(method));
		
		res = res || (path.matches("/forum/post/\\w*") && "DELETE".equalsIgnoreCase(method));
		
		res = res || (path.matches("/forum/post/\\w*") && "PUT".equalsIgnoreCase(method));
		
		res = res || (path.matches("/forum/post/\\w*/like") && "PUT".equalsIgnoreCase(method));
		
		res = res || (path.matches("/forum/post/\\w*/comment/\\w*") 
					  && "PUT".equalsIgnoreCase(method));
		
		return res;
	}

	
}
