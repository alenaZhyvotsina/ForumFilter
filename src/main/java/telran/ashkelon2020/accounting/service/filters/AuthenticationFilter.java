package telran.ashkelon2020.accounting.service.filters;

import java.io.IOException;
import java.security.Principal;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Service;

import telran.ashkelon2020.accounting.exception.UnauthorizedException;
import telran.ashkelon2020.accounting.exception.UserNotFoundException;
import telran.ashkelon2020.accounting.service.security.AccountingSecurity;

@Service
@Order(10)
public class AuthenticationFilter implements Filter{

	@Autowired
	AccountingSecurity securityService;
	
	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		
		String path = request.getServletPath();
		String method = request.getMethod();
		String token = request.getHeader("Authorization");
		
		System.out.println(path);
		System.out.println(method);
		System.out.println(token);
				
		if(!"/account/register".equalsIgnoreCase(path)
		   && !checkPathAndMethodWithoutAuthantication(path, method)) {
			
			String sessionId = request.getSession().getId();
			System.out.println(sessionId);
			
			if(sessionId != null && token == null) {
				String login = securityService.getUser(sessionId);
				if(login != null) {
					request = new WrapperRequest(request, login);
					chain.doFilter(request, response);
					return;
				}
			}
			
			try {
				String login = securityService.getLogin(token);
				request = new WrapperRequest(request, login);
				securityService.addUser(sessionId, login);
				
			} catch (UserNotFoundException e) {
				response.sendError(404, e.getMessage());
				return;
			} catch (UnauthorizedException e) {
				response.sendError(401);
				return;
			} catch (Exception e) {
				response.sendError(400);
				return;
			}
		}
		
		chain.doFilter(request, response);
	}
	
	private boolean checkPathAndMethodWithoutAuthantication(String path, String method) {
		boolean res = false;
		
		//res = (path.startsWith("/forum/") && "GET".equalsIgnoreCase(method));
		
		//res = res || (path.startsWith("/forum") && "GET".equalsIgnoreCase(method));
		res = res || "GET".equalsIgnoreCase(method);
		
		//res = res || (path.matches("/forum/posts/author/\\w*") && "GET".equalsIgnoreCase(method));
		
		res = res || (path.matches("/forum/posts/tags|period")/* && "POST".equalsIgnoreCase(method)*/);
		
		//res = res || (path.matches("/forum/posts/period") && "POST".equalsIgnoreCase(method));
		
		//res = res || (path.matches("/forum/post/\\w*/comments") && "GET".equalsIgnoreCase(method));
		
		//res = res || (path.matches("/forum/post/\\w*/author/\\w*/comments") && "GET".equalsIgnoreCase(method));
				
		return res;
	}

	private class WrapperRequest extends HttpServletRequestWrapper {

		String user;
		
		public WrapperRequest(HttpServletRequest request, String user) {
			super(request);
			this.user = user;
		}

		@Override
		public Principal getUserPrincipal() {
			return new Principal() {
				
				@Override
				public String getName() {
					return user;
				}
			};
		}
	}
	
}
