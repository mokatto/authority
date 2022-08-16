import com.google.common.io.FileBackedOutputStream;
import com.wf.captcha.ArithmeticCaptcha;
import com.wf.captcha.ChineseCaptcha;
import com.wf.captcha.base.Captcha;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.OutputStream;

public class CaptchaTest {
    public static void main(String[] args) throws FileNotFoundException {
        Captcha captcha=new ChineseCaptcha();
        String text = captcha.text();
        System.out.println(text);
        captcha.out(new FileOutputStream(new File("d:\\test.png")));
        Captcha captcha1=new ArithmeticCaptcha();
        String text1 = captcha1.text();
        System.out.println(text1);
        captcha1.out(new FileOutputStream(new File("d:\\test1.png")));

    }
}
