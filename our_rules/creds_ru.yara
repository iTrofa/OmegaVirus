rule creds_ru
{
meta:
	description = "Simple YARA rule to detect Russian credential harvesters"

strings:
	$a = "http://reninparwil.com/zapoy/gate.php"  
	$b = "http://leftthenhispar.ru/zapoy/gate.php"
	$c = "http://reptertinrom.ru/zapoy/gate.php"
 
condition: 
	($a or $b or $c)
}
