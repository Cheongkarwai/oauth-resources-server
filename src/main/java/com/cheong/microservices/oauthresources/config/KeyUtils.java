package com.cheong.microservices.oauthresources.config;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class KeyUtils {

	@Autowired
	Environment environment;

//	@Value("${access-token.private}")
//	private String privateAccessToken;
//
//	@Value("${access-token.public}")
//	private String publicAccessToken;
//
//	@Value("${refresh-token.private}")
//	private String privateRefreshToken;
//
//	@Value("${refresh-token.public}")
//	private String publicRefreshToken;

	private KeyPair accessTokenKeyPair;

	private KeyPair refreshTokenKeyPair;

	public KeyPair getAccessTokenKeyPair() {
		if (Objects.isNull(accessTokenKeyPair)) {
			accessTokenKeyPair = getKeyPair("access-refresh-token-keys/access-token-public.key", "access-refresh-token-keys/access-token-private.key");
		}

		return accessTokenKeyPair;
	}

	public KeyPair getRefreshTokenKeyPair() {
		if (Objects.isNull(refreshTokenKeyPair)) {
			refreshTokenKeyPair = getKeyPair("access-refresh-token-keys/refresh-token-public.key", "access-refresh-token-keys/refresh-token-private.key");
		}

		return refreshTokenKeyPair;
	}

	public KeyPair getKeyPair(String publicKeyPath, String privateKeyPath) {
		KeyPair keyPair;

		File publicKeyFile = new File(publicKeyPath);

		File privateKeyFile = new File(privateKeyPath);

		if (publicKeyFile.exists() && privateKeyFile.exists()) {

			KeyFactory keyFactory;
			try {
				keyFactory = KeyFactory.getInstance("RSA");

				byte[] publicKeyBytes = Files.readAllBytes(publicKeyFile.toPath());
				EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
				PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

				byte[] privateKeyBytes = Files.readAllBytes(privateKeyFile.toPath());
				PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
				PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

				keyPair = new KeyPair(publicKey, privateKey);

				return keyPair;

			} catch (NoSuchAlgorithmException e) {
				throw new RuntimeException(e);
			} catch (IOException e) {
				throw new RuntimeException(e);
			} catch (InvalidKeySpecException e) {
				throw new RuntimeException(e);
			}
		} else {
//			if(false) {
//				throw new RuntimeException("Public and private key don't exist");
//			}

			
			File directory = new File("access-refresh-token-keys");
			if (!directory.exists()) {
				directory.mkdirs();
				
			}
			try {
				KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
				keyPairGenerator.initialize(2048);
				keyPair = keyPairGenerator.generateKeyPair();

				try (FileOutputStream fos = new FileOutputStream(publicKeyPath)) {
					X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyPair.getPublic().getEncoded());
					fos.write(keySpec.getEncoded());
				}

				try (FileOutputStream fos = new FileOutputStream(privateKeyPath)) {
					X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyPair.getPrivate().getEncoded());
					fos.write(keySpec.getEncoded());
				}
			} catch (NoSuchAlgorithmException | IOException e) {
				throw new RuntimeException(e);
			}
		}

		return keyPair;
	}

	public RSAPublicKey getAccessTokenPublicKey() {
		return (RSAPublicKey) getAccessTokenKeyPair().getPublic();
	}

	public RSAPrivateKey getAccessTokenPrivateKey() {
		return (RSAPrivateKey) getAccessTokenKeyPair().getPrivate();
	}

	public RSAPublicKey getRefreshTokenPublicKey() {
		return (RSAPublicKey) getRefreshTokenKeyPair().getPublic();
	}

	public RSAPrivateKey getRefreshTokenPrivateKey() {
		return (RSAPrivateKey) getRefreshTokenKeyPair().getPrivate();
	}
}
