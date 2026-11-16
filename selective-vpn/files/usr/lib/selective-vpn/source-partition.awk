BEGIN { FS = "\t"; CONVFMT = "%.17g" }
function number(ip,    a) {
	split(ip,a,".")
	return ((a[1]*256+a[2])*256+a[3])*256+a[4]
}
function address(n,    a,b,c) {
	a=int(n/16777216); n-=a*16777216
	b=int(n/65536); n-=b*65536
	c=int(n/256)
	return a "." b "." c "." (n-c*256)
}
function power(n,    p) { p=1; while(n-->0) p*=2; return p }
# split around devices so Global needs no negated PBR matches
function partition(first,bits,    size,ip,split_needed,key) {
	size=power(32-bits)
	for(ip in excluded) if(ip>=first && ip<first+size) { split_needed=1; break }
	if(!split_needed) {
		key=address(first) "/" bits
		if(!printed[key]++) print key
	} else if(bits<32) {
		partition(first,bits+1)
		partition(first+size/2,bits+1)
	}
}
FILENAME ~ /\/devices$/ { excluded[number($1)]=1; next }
FILENAME ~ /\/lan_subnets$/ { subnets[$1]=1 }
END {
	for(subnet in subnets) {
		split(subnet,parts,"/")
		partition(number(parts[1]),parts[2]+0)
	}
}
