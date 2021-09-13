import {
  Arg,
  Ctx,
  Field,
  Mutation,
  ObjectType,
  Query,
  Resolver,
  UseMiddleware,
} from "type-graphql";
import { User } from "./entity/User";
import { compare, hash } from "bcryptjs";
import {
  createAccessToken,
  createRefreshToken,
  sendRefreshToken,
} from "./utils/jwt";
import { MyContext } from "./utils/context";
import { isAuth } from "./utils/isAuth";

@ObjectType()
class LoginResponse {
  @Field()
  accessToken: string;
  @Field(() => User)
  user: User;
}

@Resolver()
export class UserResolvers {
  @Query(() => String) //return type
  hello() {
    return "hi";
  }

  @Query(() => [User])
  @UseMiddleware(isAuth)
  users() {
    return User.find();
  }

  @Mutation(() => LoginResponse)
  async login(
    @Arg("email") email: string,
    @Arg("password") password: string,
    @Ctx() { res }: MyContext
  ): Promise<LoginResponse> {
    const user = await User.findOne({ where: { email } });

    if (!user) {
      throw new Error("could not find user");
    }

    const valid = await compare(password, user.password);

    if (!valid) {
      throw new Error("bad password");
    }

    // login successful
    sendRefreshToken(res, createRefreshToken(user));
    return {
      accessToken: createAccessToken(user),
      user,
    };
  }

  @Mutation(() => Boolean)
  async register(
    @Arg("name", () => String) name: string,
    @Arg("email", () => String) email: string,
    @Arg("company", () => String) company: string,
    @Arg("password", () => String) password: string
  ) {
    const hashedPassword = await hash(password, 12);
    try {
      User.insert({
        name: name,
        email: email,
        company: company,
        password: hashedPassword,
      });
    } catch (err) {
      console.error(err);
      return false;
    }
    return true;
  }
}
