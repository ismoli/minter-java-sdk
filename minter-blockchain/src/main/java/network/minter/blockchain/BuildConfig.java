package network.minter.blockchain;

import network.minter.blockchain.models.operational.BlockchainID;

/**
 * Created by ilja on 01/02/2020.
 */
public class BuildConfig {


    public static final boolean DEBUG = false;
    public static final String APPLICATION_ID = "network.minter.blockchain";
    public static final String BUILD_TYPE = "release";
    public static final String FLAVOR = "netMain";
    public static final int VERSION_CODE = 3;
    public static final String VERSION_NAME = "0.11.1";
    public static final String BASE_NODE_URL = "https://minter-node.apps.minter.network";
    public static BlockchainID BLOCKCHAIN_ID;

    public BuildConfig() {
    }

    static {
        BLOCKCHAIN_ID = BlockchainID.MainNet;
    }

}
