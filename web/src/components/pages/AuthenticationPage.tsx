import { cn } from "@/lib/utils"
import { Button, buttonVariants } from "@/components/ui/button"
import { UserAuthForm } from "@/components/partials/user-auth-form"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"

export default function AuthenticationPage() {
  return (
    <>
      <div className="container h-[800px] flex-col items-center justify-center grid lg:px-0">
        <div className="lg:p-8">
          <div className="mx-auto flex w-full flex-col justify-center space-y-6 w-[350px]">
            <div className="flex flex-col space-y-2 text-center">
              <Tabs className="w-full" defaultValue="login">
                <TabsList className="w-full">
                  <TabsTrigger className="w-full" value="login">Login</TabsTrigger>
                  <TabsTrigger className="w-full" value="register">Register</TabsTrigger>
                </TabsList>
                <TabsContent value="login" className="space-y-2 pt-6">
                  <h1 className="text-2xl font-semibold tracking-tight">Login to your account</h1>
                  <p className="text-sm text-muted-foreground">
                    Enter your email below to login to your account
                  </p>
                  <UserAuthForm />
                </TabsContent>
                <TabsContent value="register" className="space-y-2 pt-6">
                  <h1 className="text-2xl font-semibold tracking-tight">Create an account</h1>
                  <p className="text-sm text-muted-foreground">
                    Enter your email below to create your account
                  </p>
                  <UserAuthForm />
                </TabsContent>
              </Tabs>
            </div>
            <p className="px-8 text-center text-sm text-muted-foreground">
              By clicking continue, you agree to our{" "}
              <a
                href="/terms"
                className="underline underline-offset-4 hover:text-primary"
              >
                Terms of Service{" "}
              </a>
              and{" "}
              <a
                href="/privacy"
                className="underline underline-offset-4 hover:text-primary"
              >{" "}
                Privacy Policy
              </a>
              .
            </p>
          </div>
        </div>
      </div>
    </>
  )
}