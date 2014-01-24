/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package pcapextract;

import javax.swing.JFrame;
import org.math.plot.*;


/**
 *
 * @author shaun
 */
public class PlotPacketTrace {
    
    static long[] x = null;
    static long[] y = null;
    
    
    public void setX(long[] x) {
        this.x = x;
    }
    
    public void setY(long[] y) {
        this.y = y;
    }
    
    public boolean doPlot() {
        
        //double[] x = { 10, 20, 30, 40, 50 };
        //double[] y = { 1, 2, 3, 4, 5 };
 
        // create your PlotPanel (you can use it as a JPanel)
        Plot2DPanel plot = new Plot2DPanel();
        
        double[] newX = new double[this.x.length];
        double[] newY = new double[this.y.length];
        
        for(int i = 0; i < this.x.length; i++) {
            newX[i] = (double)this.x[i];
            newY[i] = (double)this.y[i];
        }
 
        // add a line plot to the PlotPanel
        plot.addLinePlot("packet trace", newX, newY);
 
  // put the PlotPanel in a JFrame, as a JPanel
        JFrame frame = new JFrame("skype packets");
        frame.setContentPane(plot);
        frame.setVisible(true);
        return true;
    }
}
