package br.unesp.fc.credential.sddl;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Comparator;
import net.tirasa.adsddl.ntsd.ACE;
import net.tirasa.adsddl.ntsd.SDDL;
import net.tirasa.adsddl.ntsd.SID;
import net.tirasa.adsddl.ntsd.data.AceFlag;
import net.tirasa.adsddl.ntsd.data.AceObjectFlags;
import net.tirasa.adsddl.ntsd.data.AceRights;
import net.tirasa.adsddl.ntsd.data.AceType;
import net.tirasa.adsddl.ntsd.utils.GUID;
import net.tirasa.adsddl.ntsd.utils.Hex;
import net.tirasa.adsddl.ntsd.utils.NumberFacility;

/**
 * Utility class
 * We need to upstream this code
 */
public class SDDLUtils {

    public final static String CHANGE_PASSWORD_GUID = "ab721a53-1e2f-11d0-9819-00aa0040529b";
    public final static SID SID_WORLD = newSID(1, 0); // S-1-1-0;
    public final static SID SID_SELF = newSID(5, 10); // S-1-5-10;

    private SDDLUtils() {
    }

    private static SID newSID(long identifierAuthority, int... subAuthorities) {
        SID sid = SID.newInstance(new byte[] {
            (byte)((identifierAuthority & 0xffl << 0x28) >> 0x28),
            (byte)((identifierAuthority & 0xffl << 0x20) >> 0x20),
            (byte)((identifierAuthority & 0xffl << 0x18) >> 0x18),
            (byte)((identifierAuthority & 0xffl << 0x10) >> 0x10),
            (byte)((identifierAuthority & 0xffl << 0x08) >> 0x08),
            (byte)((identifierAuthority & 0xffl << 0x00) >> 0x00),
        });
        for (int i = 0; i < subAuthorities.length; i++) {
            sid.addSubAuthority(new byte[] {
                (byte) ((subAuthorities[i] & 0xff << 0x18) >> 0x18),
                (byte) ((subAuthorities[i] & 0xff << 0x10) >> 0x10),
                (byte) ((subAuthorities[i] & 0xff << 0x08) >> 0x08),
                (byte) ((subAuthorities[i] & 0xff << 0x00) >> 0x00),
            });
        }
        return sid;
    }

    private static boolean SIDEquals(SID sid1, SID sid2) {
        if (sid1.getSize() != sid2.getSize()) {
            return false;
        }
        if (!Arrays.equals(sid1.getIdentifierAuthority(), sid2.getIdentifierAuthority())) {
            return false;
        }
        var sub1 = sid1.getSubAuthorities();
        var sub2 = sid2.getSubAuthorities();
        for (int i = 0; i < sub1.size(); i++) {
            if (!Arrays.equals(sub1.get(i), sub2.get(i))) {
                return false;
            }
        }
        return true;
    }

    public static void setUserCannotChangePassword(SDDL sddl, boolean value) {
        boolean hasWorld = false;
        boolean hasSelf = false;
        byte[] change_passowrd_guid = GUID.getGuidAsByteArray(CHANGE_PASSWORD_GUID);
        for (var it = sddl.getDacl().getAces().iterator(); it.hasNext();) {
            ACE ace = it.next();
            if (!(ace.getType().equals(AceType.ACCESS_DENIED_OBJECT_ACE_TYPE) || ace.getType().equals(AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE))
                    || !ace.getObjectFlags().getFlags().contains(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT)) {
                continue;
            }
            if (Arrays.equals(change_passowrd_guid, ace.getObjectType())) {
                if (SIDEquals(SID_SELF, ace.getSid())) {
                    hasSelf = true;
                    if (!value) {
                        // We don't need to allow self
                        it.remove();
                    } else {
                        ace.setType(value ? AceType.ACCESS_DENIED_OBJECT_ACE_TYPE : AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE);
                    }
                } else if (SIDEquals(SID_WORLD, ace.getSid())) {
                    hasWorld = true;
                    ace.setType(value ? AceType.ACCESS_DENIED_OBJECT_ACE_TYPE : AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE);
                }
            }
        }
        if (!hasWorld) {
            ACE ace = ACE.newInstance(value ? AceType.ACCESS_DENIED_OBJECT_ACE_TYPE : AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE);
            ace.setSid(SID_WORLD);
            ace.setObjectFlags(new AceObjectFlags(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT));
            ace.setObjectType(GUID.getGuidAsByteArray(CHANGE_PASSWORD_GUID));
            ace.setRights(new AceRights().addOjectRight(AceRights.ObjectRight.CR));
            sddl.getDacl().getAces().add(ace);
        }
        if (!hasSelf) {
            ACE ace = ACE.newInstance(AceType.ACCESS_DENIED_OBJECT_ACE_TYPE);
            ace.setSid(SID_SELF);
            ace.setObjectFlags(new AceObjectFlags(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT));
            ace.setObjectType(GUID.getGuidAsByteArray(CHANGE_PASSWORD_GUID));
            ace.setRights(new AceRights().addOjectRight(AceRights.ObjectRight.CR));
            sddl.getDacl().getAces().add(ace);
        }
        // Sort like Windows Server 2022
        // There are rules, but it don't apply rule 3
        // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/dbfdc00c-1e4b-4165-939b-974e8ea23733
        sddl.getDacl().getAces().sort(new Comparator<ACE>(){

            @Override
            public int compare(ACE o1, ACE o2) {
                // 1. Explicit ACEs come before inherited ACEs.
                if (!o1.getFlags().contains(AceFlag.INHERITED_ACE) && o2.getFlags().contains(AceFlag.INHERITED_ACE)) {
                    return -1;
                }
                if (o1.getFlags().contains(AceFlag.INHERITED_ACE) && !o2.getFlags().contains(AceFlag.INHERITED_ACE)) {
                    return 1;
                }

                // Don't sort inherited ACEs
                if (o1.getFlags().contains(AceFlag.INHERITED_ACE)) {
                    return 0;
                }

                // 2. Deny ACEs come before Allow ACEs.
                if ((o1.getType().equals(AceType.ACCESS_DENIED_ACE_TYPE) || o1.getType().equals(AceType.ACCESS_DENIED_OBJECT_ACE_TYPE))
                        && !o2.getType().equals(o1.getType())) {
                    return -1;
                }
                if ((o2.getType().equals(AceType.ACCESS_DENIED_ACE_TYPE) || o2.getType().equals(AceType.ACCESS_DENIED_OBJECT_ACE_TYPE))
                        && !o1.getType().equals(o2.getType())) {
                    return 1;
                }
                // 3. Regular ACEs come before object ACEs.
                // Skip

                // 4. Within each group, the ACEs are ordered lexicographically
                // (that is, based on octet string comparison rules).
                byte[] o1Bytes = o1.toByteArray();
                byte[] o2Bytes = o2.toByteArray();
                // Biggest ACE come first
                if (o1Bytes.length != o2Bytes.length) {
                    return o1Bytes.length > o2Bytes.length ? -1 : 1;
                }
                for (int i = 4; i < o1Bytes.length; i++) {
                    if (o1Bytes[i] != o2Bytes[i]) {
                        return (o1Bytes[i] & 0xff) < (o2Bytes[i] & 0xff) ? -1 : 1;
                    }
                }
                return 0;
            }

        });
    }

    public static byte[] SDDLtoByteArray(SDDL sddl) {
        final ByteBuffer buff = ByteBuffer.allocate(sddl.getSize());

        // add revision
        buff.put(sddl.getRevision());

        // add reserved
        buff.put((byte) 0x00);

        // add contro flags
        buff.put(sddl.getControlFlags()[1]);
        buff.put(sddl.getControlFlags()[0]);

        // add offset owner
        buff.position(4);
        buff.putInt(0);

        int nextAvailablePosition = 20;

        // add offset group
        buff.position(8);
        buff.putInt(0);

        // add offset sacl
        buff.position(12);

        // add SACL
        if (sddl.getSacl() == null) {
            buff.putInt(0);
        } else {
            buff.put(Hex.reverse(NumberFacility.getBytes(nextAvailablePosition)));
            buff.position(nextAvailablePosition);
            buff.put(sddl.getSacl().toByteArray());
            nextAvailablePosition += sddl.getSacl().getSize();
        }

        // add offset dacl
        buff.position(16);

        // add DACL
        if (sddl.getDacl() == null) {
            buff.putInt(0);
        } else {
            buff.put(Hex.reverse(NumberFacility.getBytes(nextAvailablePosition)));
            buff.position(nextAvailablePosition);
            buff.put(sddl.getDacl().toByteArray());
            nextAvailablePosition += sddl.getDacl().getSize();
        }

        // add owner SID
        if (sddl.getOwner() != null) {
            buff.put(Hex.reverse(NumberFacility.getBytes(nextAvailablePosition)));
            buff.position(nextAvailablePosition);
            buff.put(sddl.getOwner().toByteArray());
            int offset = nextAvailablePosition;
            nextAvailablePosition += sddl.getOwner().getSize();
            buff.position(4);
            buff.put(Hex.reverse(NumberFacility.getBytes(offset)));
        }

        // add group SID
        if (sddl.getGroup() != null) {
            buff.put(Hex.reverse(NumberFacility.getBytes(nextAvailablePosition)));
            buff.position(nextAvailablePosition);
            buff.put(sddl.getGroup().toByteArray());
            int offset = nextAvailablePosition;
            //nextAvailablePosition += sddl.getGroup().getSize();
            buff.position(8);
            buff.put(Hex.reverse(NumberFacility.getBytes(offset)));
        }

        return buff.array();

    }
}
