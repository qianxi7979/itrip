package cn.itrip.auth.service;

import java.util.List;
import java.util.Set;

import cn.itrip.beans.pojo.ItripUser;

public interface UserService {

	public void itriptxCreateUser(ItripUser user) throws Exception;

	public void updateUser(ItripUser user) throws Exception;

	public void deleteUser(Long userId) throws Exception;

	public void changePassword(Long userId, String newPassword) throws Exception;

	ItripUser findOne(Long userId) throws Exception;

	List<ItripUser> findAll() throws Exception;

	public ItripUser findByUsername(String username) throws Exception;

	public Set<String> findRoles(String username);

	public Set<String> findPermissions(String username);

	public ItripUser login(String name, String password) throws Exception;
	/**
	 * 邮箱激活
	 * @param email 用户注册油箱
	 * @param code 激活码
	 * @return 
	 * @throws Exception 
	 */
	public boolean activate(String email,String code) throws Exception;

	
}
