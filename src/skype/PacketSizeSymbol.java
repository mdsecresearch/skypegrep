package skype;

import org.biojava.bio.Annotation;
import org.biojava.bio.symbol.FundamentalAtomicSymbol;

 public class PacketSizeSymbol extends FundamentalAtomicSymbol {
 private static final long serialVersionUID = -42925484312330097L;

 public PacketSizeSymbol(Integer num, Annotation annotation) {
 super(num.toString(), annotation);
 }
 @Override
 public boolean equals(Object obj) {
 return (obj instanceof PacketSizeSymbol) ? this.getName().equals(((PacketSizeSymbol) obj).getName()) : false;
 }

 @Override
 public int hashCode() {
 return getName().hashCode();
 }
 }
