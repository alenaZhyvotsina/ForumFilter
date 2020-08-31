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

import telran.ashkelon2020.accounting.exception.NotAdminException;
import telran.ashkelon2020.accounting.service.security.AccountingSecurity;

@Service
@Order(40)
public class AdminRoleFilter implements Filter{

	@Autowired
	AccountingSecurity securityService;
	
	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		
		String path = request.getServletPath();
		
		if(checkPathOnAdmin(path)) {
			try {
				securityService.checkAdmin(request.getUserPrincipal().getName(), "Admin");
			} catch (NotAdminException e) {
				response.sendError(403, e.getMessage());
				return;
			}
		}
		chain.doFilter(request, response);
	}

	private boolean checkPathOnAdmin(String path) {
		if(path == null || path.isEmpty()) {
			return false;
		}
		 return path.contains("/role/");		
	}

}
