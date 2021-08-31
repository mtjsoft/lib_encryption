package android.text;

/**
 * @author mtj
 * @date 2021/8/31
 * @desc
 * @email mtjsoft3@gmail.com
 */
public class TextUtils {
    public static boolean isEmpty(CharSequence str) {
        if (str == null || str.equals("")) {
            return true;
        }
        return false;
    }
}
