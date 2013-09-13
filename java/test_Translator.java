
public class test_Translator {
    public static void
    main(String[] args) {
        Translator tr = new Translator();
        //Translator.set_debug(true);

        String b;

        b = tr.translate("PPPPPPAAPAAAP");
        System.out.println("Expect Partial Validator(DNAME), b=" + b);
        
        b = tr.translate("PPPPPPPPPPPPP");
        System.out.println("Expect DNSSEC Aware, b=" + b);

        b = tr.translate("PPPPPPAPAPAAP");
        System.out.println("Expect Partial Validator(Mixed), b=" + b);

        b = tr.translate("PPPPPPAAAAFAA");
        System.out.println("Expect Partial Validator(NSEC3), b=" + b);

        b = tr.translate("PPPPPPAAAAAAF");
        System.out.println("Expect Partial Validator(Permissive), b=" + b);

        b = tr.translate("PPPFPPAAAAAAA");
        System.out.println("Expect Partial Validator(TCP), b=" + b);

        b = tr.translate("PPFPPPAAAAAAA");
        System.out.println("Expect Partial Validator(Unknown), b=" + b);

        b = tr.translate("PPPPFPAAAAAAF");
        System.out.println("Expect Partial Validator(DNAME,Permissive), b=" + b);

        b = tr.translate("PPPPPPAAAAAFA");
        System.out.println("Expect Partial Validator(SlowBig), b=" + b);

        b = tr.translate("PPPFPPAAAAAFA");
        System.out.println("Expect Partial Validator(NoBig), b=" + b);

        b = tr.translate("PPPPPPAAAAAAA");
        System.out.println("Expect Validator, b=" + b);
    }
}