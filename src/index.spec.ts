import { Post } from './index'
import { plainToClass } from 'class-transformer'
import { validate } from 'class-validator'

describe('Reproduce https://security.snyk.io/vuln/SNYK-JS-CLASSVALIDATOR-1730566', () => {
  /**
   * Uses class-transformer to instantiate the object from the dangerous input.
   * The vulnerability IS NOT reproducible with this setup (class-transformer + class-validator).
   * It was fixed in version 0.3.1 https://github.com/typestack/class-transformer/commit/8f04eb9db02de708f1a20f6f2d2bb309b2fed01e of **class-transformer**
   */
  describe('when using class-transformer', () => {
    it.each([
      { forbidUnknownValues: true }, // Succeeds
      { forbidUnknownValues: false } // Succeeds
    ])('should validate input given %j options', async (validatorOptions) => {
      const userJson = JSON.parse('{"title":1233, "__proto__":{}}')  // Prototype pollution

      const instanceToValidate = plainToClass(Post, userJson)

      const errors = await validate(instanceToValidate, validatorOptions)

      expect(errors.length > 0).toBe(true)
    })
  })

  /**
   * Uses Object.assign to instantiate the object from the dangerous input
   * The vulnerability IS reproducible with this setup (Object.assign + class-validator),
   * but this is not the class-validator problem as the input object does not contain validation metadata.
   */
  describe('when using Object.assign', () => {
    it.each([
      { forbidUnknownValues: true }, // Succeeds: Even though no validation metadata is available to validate the input, it will throw one error due to unknown values
      { forbidUnknownValues: false } // Fails: No errors due to missing validation metadata :(
    ])('should validate input given %j options', async (validatorOptions) => {
      const userJson = JSON.parse('{"title":1233, "__proto__":{}}')  // Prototype pollution
      const instanceToValidate = Object.assign(new Post(), userJson); // Uses plain object assign that is vulnerable to prototype pollution

      const errors = await validate(instanceToValidate, validatorOptions)

      expect(errors.length > 0).toBe(true)
    })
  })
})
