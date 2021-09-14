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
class FieldError {
  @Field()
  message: string;
}

@ObjectType()
class UserResponse {
  @Field(() => [FieldError], { nullable: true })
  errors?: FieldError[];

  @Field(() => User, { nullable: true })
  user?: User;

  @Field(() => String, { nullable: true })
  accessToken?: string;
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

  @Mutation(() => UserResponse)
  async login(
    @Arg("email") email: string,
    @Arg("password") password: string,
    @Ctx() { res }: MyContext
  ): Promise<UserResponse> {
    const user = await User.findOne({ where: { email } });

    if (!user) {
      return {
        errors: [
          {
            message: "Username or password invalid",
          },
        ],
      };
    }

    const valid = await compare(password, user.password);

    if (!valid) {
      return {
        errors: [
          {
            message: "Username or password invalid",
          },
        ],
      };
    }

    // login successful
    sendRefreshToken(res, createRefreshToken(user));
    return {
      accessToken: createAccessToken(user),
      user,
    };
  }

  @Mutation(() => UserResponse)
  async register(
    @Arg("name", () => String) name: string,
    @Arg("email", () => String) email: string,
    @Arg("company", () => String) company: string,
    @Arg("password", () => String) password: string
  ): Promise<UserResponse> {
    const hashedPassword = await hash(password, 12);
    let user;
    try {
      const result = await User.insert({
        name: name,
        email: email,
        company: company,
        password: hashedPassword,
      });
      user = result.raw[0];
    } catch (err) {
      if (err.code === "23505") {
        return {
          errors: [
            {
              message: "username already taken",
            },
          ],
        };
      }
    }
    return { user };
  }
}
