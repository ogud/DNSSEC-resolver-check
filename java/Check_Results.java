import java.io.BufferedReader;
import java.io.IOException; 
import java.io.InputStreamReader; 

public class Check_Results {

    /* tool to grade results 
        this tool expects stdin to be a list of result strings and it
	translates them to grades 
    */
    public static void 
    main (String[] args) {
	int no = 0; 
	BufferedReader read = 
	    new BufferedReader(new InputStreamReader(System.in));
	String inp, outp;
	Translator tr = new Translator(); 
        while (true) {
	    try {
		inp = read.readLine(); 
	    } 
	    catch (IOException e) {
		System.out.println("DONE grades=" + no);
		break;
	    }
	    if (inp == null)
		break;
	    outp = tr.translate(inp);
	    System.out.println( inp + " ==> " + outp);
	    no++;
	}
	
    }
}
