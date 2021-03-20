rule zeusbotnet_yara  #kural
{
meta:
            decription=”zeusbotnet_yara”    #açıklama
            author=”Mehmet Kadir CIRIK”   #yazar
strings:
            $a ={50 4B}     #PK
            $b ={6B 64 72}  #kdr
            $c ={65 76 6F 2D 7A 65 75 73 2D 6D 61 73 74 65 72 2F 55 54}
            $mal=”MZ”
condition:
            $a and $b and $c  and $mal
}
