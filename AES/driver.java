import java.util.Scanner;

public class driver {

	public static void main(String[] args) {
		// TODO Auto-generated method stub		
		Scanner sc =  new Scanner(System.in);
		System.out.println("Enter the key:");
		String input = sc.nextLine();
		if(input.length()==32){			
			aescipher.aesRoundKeys(input);
			sc.close();
		}
		else
		{
			System.out.println("Input length is not 32");
		}			 
	}
}




