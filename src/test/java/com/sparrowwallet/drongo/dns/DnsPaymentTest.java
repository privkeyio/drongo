package com.sparrowwallet.drongo.dns;

import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.uri.BitcoinURI;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.util.Optional;

public class DnsPaymentTest {
    private static final String MAINNET_SP_ADDRESS = "sp1qqt6yk6yp7xnk5jwkjmxkyctm3udxc93l0crpdvtfmz5s2tawy4rq5q37gnh5489gj6zmzsdjealvnhnyhx7tg28nzajvh9ffl76whpp3n5vefhwm";
    private static final String TESTNET_SP_ADDRESS = "tsp1qqwxt00syn5rauhpv82cn4uq5n88yu5j6gwe6mwl9cv5050kpts9mzqhpvc7n636495v0je9acqya8gntg64wt9rla87mqleg6e8e7n2naspprl39";

    @Test
    public void validNames() {
        Assertions.assertEquals(Optional.of("craig@sparrowwallet.com"), DnsPayment.getHrn("craig@sparrowwallet.com"));
        Assertions.assertEquals(Optional.of("craig@sparrowwallet.com"), DnsPayment.getHrn("₿craig@sparrowwallet.com"));
        Assertions.assertTrue(DnsPayment.getHrn("first.last_1-x@pay.example.co").isPresent());
    }

    @Test
    public void invalidNames() {
        Assertions.assertTrue(DnsPayment.getHrn("bitcoin:bc1qwthe43xeuasklclq4kvhreluv3hu92rzej42js?x=y@pay.example.com").isEmpty());
        Assertions.assertTrue(DnsPayment.getHrn("craig@sparrowwallet.com.").isEmpty());
        Assertions.assertTrue(DnsPayment.getHrn("cr aig@sparrowwallet.com").isEmpty());
        Assertions.assertTrue(DnsPayment.getHrn("craig@sparrowwallet").isEmpty());
        Assertions.assertTrue(DnsPayment.getHrn("a@b@sparrowwallet.com").isEmpty());
        Assertions.assertThrows(IllegalArgumentException.class, () -> new DnsPaymentResolver("bitcoin:bc1qwthe43xeuasklclq4kvhreluv3hu92rzej42js?x=y@pay.example.com"));
    }

    @Test
    public void otherNetworkSilentPaymentAddress() throws Exception {
        String hrp = BitcoinURI.FIELD_SILENT_PAYMENTS_ADDRESS;
        Assumptions.assumeTrue(hrp.equals(Network.get().getSilentPaymentsAddressHrp()));
        String otherHrp = hrp.equals("sp") ? "tsp" : "sp";
        String address = hrp.equals("sp") ? MAINNET_SP_ADDRESS : TESTNET_SP_ADDRESS;
        String otherAddress = hrp.equals("sp") ? TESTNET_SP_ADDRESS : MAINNET_SP_ADDRESS;

        DnsPayment otherNetwork = getDnsPayment("bitcoin:?" + otherHrp + "=" + otherAddress);
        Assertions.assertTrue(otherNetwork.hasOtherNetworkSilentPaymentAddress());
        Assertions.assertFalse(otherNetwork.hasMisplacedSilentPaymentAddress());

        DnsPayment misplaced = getDnsPayment("bitcoin:?" + otherHrp + "=" + address);
        Assertions.assertFalse(misplaced.hasOtherNetworkSilentPaymentAddress());
        Assertions.assertTrue(misplaced.hasMisplacedSilentPaymentAddress());

        DnsPayment current = getDnsPayment("bitcoin:?" + hrp + "=" + address);
        Assertions.assertTrue(current.hasSilentPaymentAddress());
        Assertions.assertFalse(current.hasOtherNetworkSilentPaymentAddress());
        Assertions.assertFalse(current.hasMisplacedSilentPaymentAddress());

        DnsPayment none = getDnsPayment("bitcoin:?label=x");
        Assertions.assertFalse(none.hasOtherNetworkSilentPaymentAddress());
        Assertions.assertFalse(none.hasMisplacedSilentPaymentAddress());
    }

    private static DnsPayment getDnsPayment(String uri) throws Exception {
        return new DnsPayment("craig@sparrowwallet.com", new BitcoinURI(uri), new byte[0]);
    }
}
