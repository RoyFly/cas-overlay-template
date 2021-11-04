package org.jasig.cas.adaptors.jdbc;

import cn.hutool.crypto.SecureUtil;
import org.apache.commons.lang3.StringUtils;
import org.apache.shiro.dao.DataAccessException;
import org.jasig.cas.authentication.HandlerResult;
import org.jasig.cas.authentication.PreventedException;
import org.jasig.cas.authentication.UsernamePasswordCredential;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.stereotype.Component;

import javax.security.auth.login.AccountNotFoundException;
import javax.security.auth.login.FailedLoginException;
import javax.sql.DataSource;
import javax.validation.constraints.NotNull;
import java.security.GeneralSecurityException;
import java.util.Map;


/**
 * 使用了@Component注解并设置beanName，在deployerConfigContext.xml中使用
 */
@Component("customQueryDatabaseAuthenticationHandler")
public class CustomQueryDatabaseAuthenticationHandler extends AbstractJdbcUsernamePasswordAuthenticationHandler {

    @NotNull
    @Value("${cas.jdbc.authn.query.sql}")
    private String sql;

    //从cas.properties中读取加密盐
    @Value("${cas.jdbc.authn.query.encode.salt}")
    private String salt;

    @Override
    protected HandlerResult authenticateUsernamePasswordInternal(UsernamePasswordCredential transformedCredential)
            throws GeneralSecurityException, PreventedException {
        if (StringUtils.isBlank(this.sql) || null == getJdbcTemplate()) {
            throw new GeneralSecurityException("Authentication handler is not configuredcorrectly");
        }

        String userName = transformedCredential.getUsername();

        try {
            Map<String, Object> resultMap = getJdbcTemplate().queryForMap(this.sql, userName);
            String dbPassword = resultMap.get("staff_pass").toString();
            String inputPassword = transformedCredential.getPassword();
//            ShaPasswordEncoder encoder = new ShaPasswordEncoder();
//            String encryptPassword = encoder.encrypt(inputPassword, salt);
            String encryptPassword = SecureUtil.md5(inputPassword);
            if (!dbPassword.equals(encryptPassword)) {
                throw new FailedLoginException("Password does not match value on record.");
            }
        } catch (IncorrectResultSizeDataAccessException e) {
            if (e.getActualSize() == 0) {
                throw new AccountNotFoundException(userName + " not found with SQL query");
            } else {
                throw new FailedLoginException("Multiple records found for " + userName);
            }
        } catch (DataAccessException e) {
            throw new PreventedException("SQL exception while executing query for " + userName, e);
        }

        return createHandlerResult(transformedCredential, this.principalFactory.createPrincipal(userName), null);
    }


    @Override
    @Autowired(required = false)
    public void setDataSource(@Qualifier("queryDatabaseDataSource") DataSource dataSource) {
        super.setDataSource(dataSource);
    }
}