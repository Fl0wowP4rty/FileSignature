package top.flowowparty.signature;

import java.io.File;

import com.security.utils.ByteUtils;

import joptsimple.OptionParser;
import joptsimple.OptionSet;
import joptsimple.OptionSpec;
import top.flowowparty.signature.utils.CryptUtils;

public class Main {

	public static void main(String[] args) {
		OptionParser optionparser = new OptionParser();
		optionparser.allowsUnrecognizedOptions();
		optionparser.accepts("verify");
		optionparser.accepts("sign");
		optionparser.accepts("generate");
		OptionSpec<String> pub_spec = optionparser.accepts("publickey").withRequiredArg();
		OptionSpec<String> pri_spec = optionparser.accepts("privatekey").withRequiredArg();
		OptionSpec<String> file_spec = optionparser.accepts("file").withRequiredArg();
		OptionSpec<String> out_spec = optionparser.accepts("out").withRequiredArg();
		OptionSet optionset = optionparser.parse(args);

		boolean verify = optionset.has("verify");
		boolean sign = optionset.has("sign");
		boolean generate = optionset.has("generate");

		if (generate) {
			CryptUtils.createKey(optionset.has(out_spec) ? new File(out_spec.value(optionset)) : null);
			return;
		} else if (sign) {
			if (!optionset.has(file_spec))
				throw new NullPointerException("file is null");
			File file = new File(file_spec.value(optionset));
			if (file.isDirectory())
				throw new RuntimeException("target is not a file");
			CryptUtils.sign(optionset.has(out_spec) ? new File(out_spec.value(optionset)) : null, file,
					ByteUtils.hexToByte(pri_spec.value(optionset)));
			return;
		} else if (verify) {
			if (!optionset.has(file_spec))
				throw new NullPointerException("file is null");
			File file = new File(file_spec.value(optionset));
			if (file.isDirectory())
				throw new RuntimeException("target is not a file");
			CryptUtils.verify(file, ByteUtils.hexToByte(pub_spec.value(optionset)));
			return;
		}

		System.out.println("How to use:");
		System.out.println("java -jar signature.jar --generate --out yourdir");
		System.out.println("java -jar signature.jar --sign --file yourfile --privatekey yourkey");
		System.out.println("java -jar signature.jar --verify --file yourfile --publickey yourkey");
	}
}
