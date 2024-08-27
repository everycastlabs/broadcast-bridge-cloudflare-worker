import * as phc from '@phc/format';
import { WorkOS } from '@workos-inc/node';
import { parseFullName } from 'parse-full-name';
import packageJsonExample1 from "./users.json" assert { type: "json" };

// Found in the Firebase console.
const firebaseHashParameters = {
  algorithm: 'SCRYPT',
  base64_signer_key:
    'FTqhZ/HylrXPc02ncngJ2h0fzl7AYo78Yvl2nR8B4ieajp83/VtdrA/qaS4YRosY+W4XDhBViMOVcV8wXF2pbQ==',
  base64_salt_separator: 'Bw==',
  rounds: 8,
  mem_cost: 14,
};

const workOS = new WorkOS('key');

for await (const fuser of users) {
  const name = parseFullName(fuser.displayName, 'all', 1, 0, 0);

  const user = await WorkOS.userManagement.createUser({
    email: fuser.email,
    emailVerified: fuser.emailVerified,
    firstName: name.first,
    lastName: name.last,
  });

  if (fuser.passwordHash) {
    const passwordHash = phc.serialize({
      id: 'firebase-scrypt',
      version: 1,
      hash: Buffer.from(fuser.passwordHash, 'base64'),
      salt: Buffer.from(fuser.salt, 'base64'),
      params: {
        r: firebaseHashParameters.rounds,
        m: firebaseHashParameters.mem_cost,
        ss: Buffer.from(firebaseHashParameters.base64_salt_separator, 'base64'),
        sk: Buffer.from(firebaseHashParameters.base64_signer_key, 'base64'),
      },
    });

    workOS.userManagement.updateUser({
      userId: user.id,
      passwordHashType: 'firebase-scrypt',
      passwordHash,
    });
  }
}
