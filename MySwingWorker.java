import java.util.concurrent.ExecutionException;
import java.util.concurrent.Semaphore;

import javax.swing.SwingWorker;

public class MySwingWorker extends SwingWorker<String, Void> {

	protected final Semaphore available = new Semaphore(1, true);
	protected String ip_address = null;
	protected String results = null;
	
	MySwingWorker(String ip_address) {
		this.ip_address = ip_address;
	}
	
	public String getResults() {
		return results;
	}
	
	@Override
	public String doInBackground() throws InterruptedException {
		available.acquire();
		String g = "";
		String tr = "";
		try {
		    g = DNSSEC_resolver_check.evaluate_resolver(ip_address); 
		}
		catch (Exception exc) {
		    System.err.println("Exception: " + exc);
		    g = "Failure: " + exc.getMessage();
		}
		available.release();
		if (g != null) {
		    tr = new Translator().translate(g);
		    return g + ", " + tr;
		} else {
			return "Failed";				
		}
	}
	
	@Override
	public void done() {
		try {
			results = get();			
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ExecutionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
