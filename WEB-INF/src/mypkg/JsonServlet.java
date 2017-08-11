// To save as "<CATALINA_HOME>\webapps\helloservlet\WEB-INF\src\mypkg\EchoServlet.java"
package mypkg;

import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.util.*;
import java.lang.*;
import java.time.*;

public class JsonServlet extends HttpServlet {

   @Override
   public void doGet(HttpServletRequest request, HttpServletResponse response)
               throws IOException, ServletException {
      // Set the response message's MIME type
      response.setContentType("application/json; charset=UTF-8");
      // Allocate a output writer to write the response message into the network socket
      // Write the response message, in an HTML page
      PrintWriter out = response.getWriter();
      try {

         // Retrieve the value of the query parameter "servername" (from text field)
         String servername = request.getParameter("servername");

         // Create a random file name
         int fileName = (int) Math.floor(Math.random()*1000000);

         File file = new File(fileName+".json");
         Process p = Runtime.getRuntime().exec("C:/apache-tomcat-9.0.0.M21/webapps/TLSValidate/TLSValidateSrc/Mono/bin/mono C:/apache-tomcat-9.0.0.M21/webapps/TLSValidate/TLSValidateSrc/TLSValidate.exe "+ servername+" -json "+fileName+".json");

         try
         {
           p.waitFor();
           Scanner scan = new Scanner(file);
                while(scan.hasNext()){
                  out.println(scan.nextLine());
                }
                out.flush();
                scan.close();
                file.delete();


         }

         catch(InterruptedException e)
         {
         }



      }catch(Exception e){
        out.println("This server is not secure or can not be found");
        out.println("Please check that an SSL/TLS protocol is in place and that this server exists.");
      }
       finally {
         out.close();  // Always close the output writer
      }
   }

   // Redirect POST request to GET request.
   @Override
   public void doPost(HttpServletRequest request, HttpServletResponse response)
               throws IOException, ServletException {
      doGet(request, response);
   }

   // Filter the string for special HTML characters to prevent
   // command injection attack
   private static String htmlFilter(String message) {
      if (message == null) return null;
      int len = message.length();
      StringBuffer result = new StringBuffer(len + 20);
      char aChar;

      for (int i = 0; i < len; ++i) {
         aChar = message.charAt(i);
         switch (aChar) {
             case '<': result.append("&lt;"); break;
             case '>': result.append("&gt;"); break;
             case '&': result.append("&amp;"); break;
             case '"': result.append("&quot;"); break;
             default: result.append(aChar);
         }
      }
      return (result.toString());
   }
}
