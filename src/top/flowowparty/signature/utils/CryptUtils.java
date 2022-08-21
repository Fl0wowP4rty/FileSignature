package top.flowowparty.signature.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

import com.security.SM3Digest;
import com.security.math.SM2;
import com.security.utils.ByteUtils;
import com.security.utils.SM2Utils;

public class CryptUtils {
	/**
	 * 生成随机密钥对
	 */
	public static void createKey(File dir) {
		File pub = new File("key.pub");
		File pri = new File("key.pri");

		if (dir != null) {
			if (!dir.exists()) {
				dir.mkdirs();
			}
			pub = new File(dir, "key.pub");
			pri = new File(dir, "key.pri");
		}
		SM2 sm2 = SM2.Instance();
		AsymmetricCipherKeyPair key = sm2.ecc_key_pair_generator.generateKeyPair();
		ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters) key.getPrivate();
		ECPublicKeyParameters ecpub = (ECPublicKeyParameters) key.getPublic();
		BigInteger privateKey = ecpriv.getD();
		ECPoint publicKey = ecpub.getQ();

		String prikey = ByteUtils.byteToHex(privateKey.toByteArray());
		String pubkey = ByteUtils.byteToHex(publicKey.getEncoded());

		try {
			System.out.println("写出公钥：" + pub.getAbsolutePath());
			FileOutputStream pub_writer = new FileOutputStream(pub);
			pub_writer.write(pubkey.getBytes("UTF-8"));
			pub_writer.close();

			System.out.println("写出私钥：" + pri.getAbsolutePath());
			FileOutputStream pri_writer = new FileOutputStream(pri);
			pri_writer.write(prikey.getBytes("UTF-8"));
			pri_writer.close();
		} catch (IOException e) {
			e.printStackTrace();
		}

		System.out.println("公钥：" + pubkey);
		System.out.println("私钥：" + prikey);

	}

	/**
	 * 摘要
	 * 
	 * @return
	 */
	public static void sign(File dir, File file, byte[] prikey) {
		File digest = new File(file.getName() + ".digest");
		File signature = new File(file.getName() + ".signature");
		if (dir != null) {
			if (!dir.exists()) {
				dir.mkdirs();
			}
			digest = new File(dir, file.getName() + ".digest");
			signature = new File(dir, file.getName() + ".signature");
		} else {
			File partent = file.getParentFile();
			if (partent != null && partent.isDirectory()) {
				digest = new File(partent, file.getName() + ".digest");
				signature = new File(partent, file.getName() + ".signature");
			}
		}
		// 1.摘要
		byte[] md = new byte[32];
		SM3Digest sm = new SM3Digest();
		byte[] msg = getSHA256(file);
		sm.update(msg, 0, msg.length);
		sm.doFinal(md, 0);

		try {
			System.out.println("写出摘要：" + digest.getAbsolutePath());
			FileOutputStream digest_writer = new FileOutputStream(digest);
			digest_writer.write(md);
			digest_writer.close();
		} catch (IOException e) {
			e.printStackTrace();
		}

		byte[] sign = null; // 摘要签名
		try {
			sign = SM2Utils.sign(msg, prikey, md);
		} catch (IllegalArgumentException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		try {
			System.out.println("写出签名：" + signature.getAbsolutePath());
			FileOutputStream signature_writer = new FileOutputStream(signature);
			signature_writer.write(sign);
			signature_writer.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * 验签
	 * 
	 * @return
	 */
	public static void verify(File file, byte[] pubkey) {
		File digest = new File(file.getName() + ".digest");
		File signature = new File(file.getName() + ".signature");
		File partent = file.getParentFile();
		if (partent != null && partent.isDirectory()) {
			digest = new File(partent, file.getName() + ".digest");
			signature = new File(partent, file.getName() + ".signature");
		}
		byte[] msg = getSHA256(file);

		byte[] digest_bytes = null;
		try {
			FileInputStream digest_input = new FileInputStream(digest);
			digest_bytes = new byte[digest_input.available()];
			digest_input.read(digest_bytes);
			digest_input.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
		byte[] signature_bytes = null;
		try {
			FileInputStream signature_input = new FileInputStream(signature);
			signature_bytes = new byte[signature_input.available()];
			signature_input.read(signature_bytes);
			signature_input.close();
		} catch (IOException e) {
			e.printStackTrace();
		}

		try {
			boolean ret = SM2Utils.verifySign(msg, pubkey, digest_bytes, signature_bytes);
			System.out.println("验证结果：" + ret);
		} catch (IllegalArgumentException | IOException e) {
			e.printStackTrace();
		}
	}

	public static byte[] getSHA256(File f) {
		byte[] b = null;
		try {
			byte[] buffer = new byte[8192];
			int len = 0;
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			FileInputStream fis = new FileInputStream(f);
			while ((len = fis.read(buffer)) != -1) {
				md.update(buffer, 0, len);
			}
			fis.close();
			b = md.digest();
		} catch (NoSuchAlgorithmException | IOException e) {
			e.printStackTrace();
		}
		return b;
	}

}
